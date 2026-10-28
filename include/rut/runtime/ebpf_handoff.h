#pragma once

#include "rut/common/ebpf_handoff_bytecode.h"

#include <errno.h>
#include <linux/bpf.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rut {
// Shard-owned cold loader/control operations. No LLVM/libbpf or heap allocation.
struct EbpfHandoffKernel {
    enum Fd : u8 { Source, Target, State, Command, Parser, Verdict, Commit, Ring, Count };
    enum class Result : u8 { Committed, Retry, Error };
    int fds[Count] = {-1, -1, -1, -1, -1, -1, -1, -1};
    void* consumer = MAP_FAILED;
    void* producer = MAP_FAILED;
    u32 page_size = 0;
    u32 ring_size = 0;
    char verifier[16384]{};
    EbpfHandoffKernel() = default;
    EbpfHandoffKernel(const EbpfHandoffKernel&) = delete;
    EbpfHandoffKernel& operator=(const EbpfHandoffKernel&) = delete;
    ~EbpfHandoffKernel() { destroy(); }
    static int call(int command, union bpf_attr& attr) {
        return static_cast<int>(syscall(SYS_bpf, command, &attr, sizeof(attr)));
    }
    void destroy() {
        if (consumer != MAP_FAILED) munmap(consumer, page_size);
        if (producer != MAP_FAILED) munmap(producer, page_size + 2ull * ring_size);
        consumer = producer = MAP_FAILED;
        for (int& fd : fds) {
            if (fd >= 0) close(fd);
            fd = -1;
        }
    }
    // Single shard consumer. Notifications announce verdict completion only;
    // they do not prove that the target's TCP output backlog has drained.
    bool next_notification(ebpf::HandoffNotification& out) {
        if (consumer == MAP_FAILED || producer == MAP_FAILED) return false;
        auto* position = static_cast<u64*>(consumer);
        auto* published = static_cast<u64*>(producer);
        u64 offset = __atomic_load_n(position, __ATOMIC_RELAXED);
        const u64 kEnd = __atomic_load_n(published, __ATOMIC_ACQUIRE);
        auto* data = static_cast<u8*>(producer) + page_size;
        while (offset < kEnd) {
            auto* record = reinterpret_cast<u32*>(data + (offset & (ring_size - 1u)));
            const u32 kLength = __atomic_load_n(record, __ATOMIC_ACQUIRE);
            if (kLength & (1u << 31u)) return false;
            const u32 kPayload = kLength & ((1u << 30u) - 1u);
            // The map/program are private to this shard; malformed records are
            // an invariant failure and must not let the consumer overrun them.
            if (kPayload > ring_size - 8u) return false;
            const bool kValid = !(kLength & (1u << 30u)) && kPayload == sizeof(out);
            if (kValid) __builtin_memcpy(&out, record + 2, sizeof(out));
            offset += (kPayload + 8ull + 7ull) & ~7ull;
            __atomic_store_n(position, offset, __ATOMIC_RELEASE);
            if (kValid) return true;
        }
        return false;
    }
    static bool update(int map, const void* key, const void* value, u64 flags = BPF_ANY) {
        union bpf_attr attr{};
        attr.map_fd = static_cast<u32>(map);
        attr.key = reinterpret_cast<uintptr_t>(key);
        attr.value = reinterpret_cast<uintptr_t>(value);
        attr.flags = flags;
        return call(BPF_MAP_UPDATE_ELEM, attr) == 0;
    }
    static bool remove(int map, const void* key) {
        union bpf_attr attr{};
        attr.map_fd = static_cast<u32>(map);
        attr.key = reinterpret_cast<uintptr_t>(key);
        return call(BPF_MAP_DELETE_ELEM, attr) == 0;
    }
    static bool remove_if_present(int map, const void* key) {
        return remove(map, key) || errno == ENOENT;
    }
    static bool cookie(int fd, u64& out) {
        socklen_t length = sizeof(out);
        return getsockopt(fd, SOL_SOCKET, SO_COOKIE, &out, &length) == 0 && length == sizeof(out);
    }
    static bool output_progress(int fd, u64& out) {
        // Read ACKed bytes first, then the TCP send queue (write_seq - snd_una).
        // ACKs between the two calls only make this underestimate accepted
        // bytes. This is a TCP-sequence ordering barrier, not a peer-ACK wait.
        struct Info {
            u8 prefix[120];
            u64 bytes_acked;
        } info{};
        static_assert(offsetof(Info, bytes_acked) == 120);
        socklen_t length = sizeof(info);
        constexpr int kTcpInfo = 11;
        if (getsockopt(fd, IPPROTO_TCP, kTcpInfo, &info, &length) != 0) return false;
        if (length < sizeof(info) || (info.prefix[0] != 1 && info.prefix[0] != 8)) {
            errno = EOPNOTSUPP;
            return false;
        }
        int queued = 0;
        if (ioctl(fd, SIOCOUTQ, &queued) != 0 || queued < 0) return false;
        out = info.bytes_acked + static_cast<u32>(queued);
        return true;
    }
    int map(bpf_map_type type, u32 key_size, u32 value_size, u32 entries) {
        union bpf_attr attr{};
        attr.map_type = type;
        attr.key_size = key_size;
        attr.value_size = value_size;
        attr.max_entries = entries;
        return call(BPF_MAP_CREATE, attr);
    }
    int load(ebpf::Instruction* code, u32 count, bpf_prog_type type, bpf_attach_type attach) {
        constexpr char kLicense[] = "GPL";
        union bpf_attr attr{};
        attr.prog_type = type;
        attr.expected_attach_type = attach;
        attr.insn_cnt = count;
        attr.insns = reinterpret_cast<uintptr_t>(code);
        attr.license = reinterpret_cast<uintptr_t>(kLicense);
        attr.log_buf = reinterpret_cast<uintptr_t>(verifier);
        attr.log_size = sizeof(verifier);
        attr.log_level = 1;
        return call(BPF_PROG_LOAD, attr);
    }
    bool attach(int program, bpf_attach_type type) {
        union bpf_attr attr{};
        attr.target_fd = static_cast<u32>(fds[Source]);
        attr.attach_bpf_fd = static_cast<u32>(program);
        attr.attach_type = type;
        return call(BPF_PROG_ATTACH, attr) == 0;
    }
    const char* init(u32 entries = 1024,
                     bool packet_verdict = false,
                     const ebpf::HandoffCode* emitted = nullptr,
                     bool tunnel = false) {
        static_assert(BPF_FUNC_get_socket_cookie == 46);
        static_assert(BPF_FUNC_sk_redirect_hash == 72);
        static_assert(BPF_FUNC_ringbuf_output == 130);
        static_assert(BPF_SK_SKB_VERDICT == 38);
        static_assert(sizeof(bpf_insn) == sizeof(ebpf::Instruction));
        if (tunnel && !packet_verdict) {
            errno = EINVAL;
            return "tunnel_attach_type";
        }
        fds[Source] = map(BPF_MAP_TYPE_SOCKHASH, sizeof(u64), sizeof(u32), entries);
        if (fds[Source] < 0) return "source_map";
        fds[Target] = map(BPF_MAP_TYPE_SOCKHASH, sizeof(u64), sizeof(u32), entries);
        if (fds[Target] < 0) return "target_map";
        fds[State] = map(BPF_MAP_TYPE_HASH, sizeof(u64), sizeof(ebpf::HandoffState), entries);
        if (fds[State] < 0) return "state_map";
        fds[Command] = map(BPF_MAP_TYPE_ARRAY, sizeof(u32), sizeof(ebpf::HandoffCommand), 1);
        if (fds[Command] < 0) return "command_map";
        if (packet_verdict && !tunnel) {
            const long kPage = sysconf(_SC_PAGESIZE);
            if (kPage <= 0 || entries > (1u << 25u)) {
                errno = EINVAL;
                return "ring_size";
            }
            page_size = static_cast<u32>(kPage);
            ring_size = page_size;
            while (ring_size < entries * 32ull) ring_size *= 2u;
            fds[Ring] = map(BPF_MAP_TYPE_RINGBUF, 0, 0, ring_size);
            if (fds[Ring] < 0) return "ring_map";
            consumer = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fds[Ring], 0);
            if (consumer == MAP_FAILED) return "ring_consumer";
            producer = mmap(
                nullptr, page_size + 2ull * ring_size, PROT_READ, MAP_SHARED, fds[Ring], page_size);
            if (producer == MAP_FAILED) return "ring_producer";
        }
        ebpf::HandoffCode code{};
        if (tunnel)
            ebpf::emit_tunnel_bytecode(code);
        else if (packet_verdict)
            ebpf::emit_packet_handoff_bytecode(code);
        else
            ebpf::emit_handoff_bytecode(code);
        if (emitted) {
            if (!packet_verdict || __builtin_memcmp(emitted, &code, sizeof(code)) != 0) {
                errno = EINVAL;
                return "instruction_template";
            }
            code = *emitted;
        }
        code.parser[code.parser_state_map].immediate = fds[State];
        code.verdict[code.verdict_state_map].immediate = fds[State];
        code.verdict[code.verdict_target_map].immediate = fds[Target];
        if (packet_verdict && !tunnel) code.verdict[code.verdict_ring_map].immediate = fds[Ring];
        code.commit[code.commit_state_map].immediate = fds[State];
        code.commit[code.commit_command_map].immediate = fds[Command];
        if (!packet_verdict) {
            fds[Parser] = load(
                code.parser, code.parser_count, BPF_PROG_TYPE_SK_SKB, BPF_SK_SKB_STREAM_PARSER);
            if (fds[Parser] < 0) return "parser_load";
        }
        const auto kAttach = packet_verdict ? BPF_SK_SKB_VERDICT : BPF_SK_SKB_STREAM_VERDICT;
        fds[Verdict] = load(code.verdict, code.verdict_count, BPF_PROG_TYPE_SK_SKB, kAttach);
        if (fds[Verdict] < 0) return "verdict_load";
        if (!tunnel)
            fds[Commit] = load(code.commit,
                               code.commit_count,
                               BPF_PROG_TYPE_SOCKET_FILTER,
                               static_cast<bpf_attach_type>(0));
        if (!tunnel && fds[Commit] < 0) return "commit_load";
        if (!packet_verdict && !attach(fds[Parser], BPF_SK_SKB_STREAM_PARSER))
            return "parser_attach";
        if (!attach(fds[Verdict], kAttach)) return "verdict_attach";
        return nullptr;
    }
    // Call before an HTTP request can cause any upstream response. The target
    // map has no receive programs; only the source inherits parser/verdict.
    bool enroll(int source,
                int target,
                u64& source_cookie,
                u64& target_cookie,
                u32 connection_id = 0,
                u32 generation = 0) {
        if (!cookie(source, source_cookie) || !cookie(target, target_cookie)) return false;
        ebpf::HandoffState state{};
        state.target_cookie = target_cookie;
        state.connection_id = connection_id;
        state.generation = generation;
        const u32 kTarget = static_cast<u32>(target), kSource = static_cast<u32>(source);
        if (!update(fds[Target], &target_cookie, &kTarget, BPF_NOEXIST)) return false;
        if (!update(fds[State], &source_cookie, &state, BPF_NOEXIST)) {
            remove(fds[Target], &target_cookie);
            return false;
        }
        if (!update(fds[Source], &source_cookie, &kSource, BPF_NOEXIST)) {
            remove(fds[State], &source_cookie);
            remove(fds[Target], &target_cookie);
            return false;
        }
        return true;
    }
    bool inspect(u64 source_cookie, ebpf::HandoffState& out) const {
        union bpf_attr attr{};
        attr.map_fd = static_cast<u32>(fds[State]);
        attr.key = reinterpret_cast<uintptr_t>(&source_cookie);
        attr.value = reinterpret_cast<uintptr_t>(&out);
        return call(BPF_MAP_LOOKUP_ELEM, attr) == 0;
    }
    Result commit(u64 source_cookie, u32 copied_and_sent, u32 remaining) {
        if (!remaining || remaining > ebpf::kHandoffBudgetMask) return Result::Error;
        ebpf::HandoffState state{};
        if (!inspect(source_cookie, state) || state.failed) return Result::Error;
        const u32 kPhase = static_cast<u32>(state.control >> 32u);
        if ((kPhase != 0 && kPhase != ebpf::kHandoffOwned) ||
            static_cast<u32>(state.control) != copied_and_sent)
            return Result::Retry;
        const ebpf::HandoffCommand kCommand{
            source_cookie,
            state.control,
            (static_cast<u64>(ebpf::kHandoffOwned | remaining) << 32u) | copied_and_sent};
        return run_command(kCommand);
    }
    Result publish_limit(u64 source_cookie, u32 absolute_end) {
        if (!absolute_end) return Result::Error;
        const ebpf::HandoffCommand kCommand{source_cookie, ~u64{0}, absolute_end};
        return run_command(kCommand);
    }
    Result run_command(const ebpf::HandoffCommand& command) {
        constexpr u32 kKey = 0;
        if (!update(fds[Command], &kKey, &command)) return Result::Error;
        // The packet is a test-run carrier only; the control program reads the
        // shard-private command map and changes state through one atomic CAS.
        const u8 kPacket[64]{};
        union bpf_attr attr{};
        attr.test.prog_fd = static_cast<u32>(fds[Commit]);
        attr.test.data_size_in = sizeof(kPacket);
        attr.test.data_in = reinterpret_cast<uintptr_t>(kPacket);
        attr.test.repeat = 1;
        if (call(BPF_PROG_TEST_RUN, attr) != 0) return Result::Error;
        return attr.test.retval ? Result::Committed : Result::Retry;
    }
    bool retire(u64 source_cookie, u64 target_cookie) {
        // Caller closes the flow on failure; never retry by copying a flow after
        // ownership may have committed. Map deletion does not drain TX backlog.
        // TCP teardown can already unlink a socket from its SOCKHASH. Repeated
        // cleanup is safe; unrelated errors still fail rather than hiding leaks.
        bool ok = remove_if_present(fds[Source], &source_cookie);
        ok = remove_if_present(fds[State], &source_cookie) && ok;
        ok = remove_if_present(fds[Target], &target_cookie) && ok;
        return ok;
    }
};
}  // namespace rut
