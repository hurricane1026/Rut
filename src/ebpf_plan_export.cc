#include "rut/common/ebpf_bytecode.h"
#include "rut/common/ebpf_plan.h"
#include "rut/common/types.h"
#include "rut/native_program.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

namespace rut {
namespace {
struct Writer {
    int fd;
    bool ok = true;
    void bytes(const char* data, u32 length) {
        while (ok && length) {
            const ssize_t kN = write(fd, data, length);
            if (kN < 0 && errno == EINTR) continue;
            if (kN <= 0) {
                ok = false;
                return;
            }
            data += kN;
            length -= static_cast<u32>(kN);
        }
    }
    void text(const char* data) { bytes(data, static_cast<u32>(strlen(data))); }
    void number(u32 value) {
        char data[10];
        u32 position = sizeof(data);
        do {
            data[--position] = static_cast<char>('0' + value % 10);
            value /= 10;
        } while (value);
        bytes(data + position, sizeof(data) - position);
    }
    void string(const char* data, u32 length) {
        text("\"");
        constexpr char kHex[] = "0123456789abcdef";
        for (u32 i = 0; i < length; ++i) {
            const u8 kByte = static_cast<u8>(data[i]);
            if (kByte == '"' || kByte == '\\') {
                text("\\");
                bytes(data + i, 1);
            } else if (kByte < 32) {
                const char kEscaped[] = {'\\', 'u', '0', '0', kHex[kByte >> 4u], kHex[kByte & 15u]};
                bytes(kEscaped, sizeof(kEscaped));
            } else
                bytes(data + i, 1);
        }
        text("\"");
    }
};
}  // namespace
bool write_ebpf_plan_json(const NativeProgram& program, int fd) {
    if (!program.has_ebpf_plan) return false;
    const auto& plan = program.ebpf_plan;
    Writer writer{fd};
    writer.text("{\"version\":");
    writer.number(plan.version);
    writer.text(
        ",\"scope\":\"body-only\",\"routing\":\"userspace\",\"headers\":\"userspace\","
        "\"active_routes\":0,\"runtime_handoff\":\"unavailable\",\"candidate_count\":");
    writer.number(plan.candidate_count);
    writer.text(",\"bytecode\":{\"parser_bytes\":");
    writer.number(plan.parser_instructions * sizeof(ebpf::Instruction));
    writer.text(",\"verdict_bytes\":");
    writer.number(plan.verdict_instructions * sizeof(ebpf::Instruction));
    writer.text(
        ",\"frame_bytes\":4096,\"relocations\":{\"front_port_instruction\":3,"
        "\"budget_map_instruction\":6,\"socket_map_instruction\":22}},"
        "\"capabilities\":{\"program_type\":14,\"attach_types\":[4,5],"
        "\"map_types\":[15,2],\"helpers\":[1,52]},\"handoff\":{\"mode\":\"packet-verdict\","
        "\"verdict_bytes\":");
    writer.number(plan.handoff.verdict_count * sizeof(ebpf::Instruction));
    writer.text(",\"commit_bytes\":");
    writer.number(plan.handoff.commit_count * sizeof(ebpf::Instruction));
    writer.text(",\"relocations\":{\"verdict_state_map\":");
    writer.number(plan.handoff.verdict_state_map);
    writer.text(",\"verdict_target_map\":");
    writer.number(plan.handoff.verdict_target_map);
    writer.text(",\"verdict_ring_map\":");
    writer.number(plan.handoff.verdict_ring_map);
    writer.text(",\"commit_command_map\":");
    writer.number(plan.handoff.commit_command_map);
    writer.text(",\"commit_state_map\":");
    writer.number(plan.handoff.commit_state_map);
    writer.text(
        "},\"program_types\":[14,1],\"attach_types\":[38],"
        "\"map_types\":[18,1,2,27],\"helpers\":[1,46,72,130]},\"routes\":[");
    for (u32 i = 0; i < plan.route_count; ++i) {
        if (i) writer.text(",");
        const auto& entry = program.config.routes[i];
        const auto& route = plan.routes[i];
        writer.text("{\"route_id\":");
        writer.number(i);
        writer.text(",\"method\":");
        writer.number(entry.method);
        writer.text(",\"path\":");
        writer.string(entry.path, entry.path_len);
        writer.text(",\"decision\":");
        writer.text(route.decision == ebpf::Decision::BodyCandidate ? "\"body-candidate\""
                                                                    : "\"userspace\"");
        writer.text(",\"reason\":");
        const char* reason = ebpf::reason_name(route.reason);
        writer.string(reason, static_cast<u32>(strlen(reason)));
        if (route.decision == ebpf::Decision::BodyCandidate) {
            writer.text(",\"upstream_id\":");
            writer.number(route.upstream_id);
            writer.text(",\"request_policy_id\":");
            writer.number(route.request_policy_id);
            writer.text(",\"response_policy_id\":");
            writer.number(route.response_policy_id);
        }
        writer.text("}");
    }
    writer.text("]}\n");
    return writer.ok;
}
bool export_ebpf_bytecode(const NativeProgram& program,
                          const char* prefix,
                          char* error,
                          u32 error_size) {
    if (!error || !error_size) return false;
    error[0] = '\0';
    if (!program.has_ebpf_plan || !program.ebpf_plan.candidate_count) {
        snprintf(error, error_size, "no eBPF body candidate; use --ebpf-plan for route reasons");
        return false;
    }
    if (!prefix || !*prefix) {
        snprintf(error, error_size, "empty eBPF output prefix");
        return false;
    }
    struct Outputs {
        char paths[5][4096]{};
        bool created[5]{};
        bool committed = false;
        ~Outputs() {
            if (!committed)
                for (u32 i = 0; i < 5; ++i)
                    if (created[i]) unlink(paths[i]);
        }
    } outputs;
    const char* const kSuffixes[] = {
        "parser.bpf", "verdict.bpf", "packet-verdict.bpf", "handoff-commit.bpf", "json"};
    const auto& code = program.ebpf_plan.bytecode;
    const auto& handoff = program.ebpf_plan.handoff;
    const void* const kData[] = {code.parser, code.verdict, handoff.verdict, handoff.commit};
    const u32 kLengths[] = {sizeof(code.parser),
                            sizeof(code.verdict),
                            handoff.verdict_count * static_cast<u32>(sizeof(ebpf::Instruction)),
                            handoff.commit_count * static_cast<u32>(sizeof(ebpf::Instruction))};
    for (u32 i = 0; i < 5; ++i) {
        const int kLength =
            snprintf(outputs.paths[i], sizeof(outputs.paths[i]), "%s.%s", prefix, kSuffixes[i]);
        if (kLength < 0 || static_cast<u32>(kLength) >= sizeof(outputs.paths[i])) {
            snprintf(error, error_size, "eBPF output path too long");
            return false;
        }
        const int kFd = open(outputs.paths[i], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (kFd < 0) {
            snprintf(error, error_size, "cannot create eBPF output: %s", strerror(errno));
            return false;
        }
        outputs.created[i] = true;
        bool ok;
        if (i == 4)
            ok = write_ebpf_plan_json(program, kFd);
        else {
            Writer writer{kFd};
            writer.bytes(static_cast<const char*>(kData[i]), kLengths[i]);
            ok = writer.ok;
        }
        if (close(kFd) != 0) ok = false;
        if (!ok) {
            snprintf(error, error_size, "cannot write eBPF output");
            return false;
        }
    }
    outputs.committed = true;
    return true;
}
}  // namespace rut
