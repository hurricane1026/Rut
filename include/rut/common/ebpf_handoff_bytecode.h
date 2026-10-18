#pragma once

#include "rut/common/ebpf_bytecode.h"

namespace rut::ebpf {
// One source socket per state entry. The receive callback serializes parser and
// verdict; userspace changes ownership only through the control program's CAS.
struct HandoffState {
    u64 control = 0;  // high u32: phase/budget; low u32: bytes passed to recv()
    u32 frame = 0;
    u32 failed = 0;
    u64 target_cookie = 0;
    u32 pass_limit = 0;
    u32 tail_body = 0;
    u32 connection_id = 0;
    u32 generation = 0;
};
struct HandoffNotification {
    u64 source_cookie;
    u32 connection_id;
    u32 generation;
};
struct HandoffCommand {
    u64 source_cookie;
    u64 expected;
    u64 desired;
};
static_assert(sizeof(HandoffState) == 40);
static_assert(__builtin_offsetof(HandoffState, target_cookie) == 16);
static_assert(__builtin_offsetof(HandoffState, tail_body) == 28);
static_assert(__builtin_offsetof(HandoffState, connection_id) == 32);
static_assert(sizeof(HandoffNotification) == 16);
static_assert(sizeof(HandoffCommand) == 24);
struct HandoffCode {
    Instruction parser[192]{};
    Instruction verdict[256]{};
    Instruction commit[64]{};
    u32 parser_count = 0;
    u32 verdict_count = 0;
    u32 commit_count = 0;
    u32 parser_state_map = 0;
    u32 verdict_state_map = 0;
    u32 verdict_target_map = 0;
    u32 verdict_ring_map = 0;
    u32 commit_command_map = 0;
    u32 commit_state_map = 0;
};
constexpr u32 kHandoffFrameBytes = 65536;
constexpr u32 kHandoffOwned = 0x80000000u;
constexpr u32 kHandoffPending = 0x40000000u;
constexpr u32 kHandoffBudgetMask = 0x3fffffffu;
inline u32 handoff_budget(u64 control) {
    return static_cast<u32>(control >> 32u) & kHandoffBudgetMask;
}
namespace handoff_detail {
struct Builder {
    Instruction* code;
    u32 count = 0;
    u32 add(u8 op, u8 dst, u8 src = 0, i16 off = 0, i32 imm = 0) {
        code[count] = instruction(op, dst, src, off, imm);
        return count++;
    }
    void jump(u32 from, u32 to) { code[from].offset = static_cast<i16>(to - from - 1); }
    u32 map(u8 dst) {
        const u32 kIndex = add(0x18, dst, 1);
        add(0, 0);
        return kIndex;
    }
    void stack_key() {
        add(0xbf, 2, 10);
        add(0x07, 2, 0, 0, -8);
    }
    u32 state_lookup() {
        add(0xbf, 6, 1);         // preserve skb
        add(0x85, 0, 0, 0, 46);  // get_socket_cookie(skb)
        add(0x7b, 10, 0, -8);
        const u32 kMap = map(1);
        stack_key();
        add(0x85, 0, 0, 0, kMapLookupHelper);
        return kMap;
    }
};
}  // namespace handoff_detail
inline void emit_handoff_bytecode(HandoffCode& out) {
    out = {};
    using handoff_detail::Builder;
    Builder parser{out.parser};
    out.parser_state_map = parser.state_lookup();
    const u32 kParserMissing = parser.add(0x15, 0, 0, 0, 0);
    parser.add(0xbf, 7, 0);
    u32 owned[4]{}, pending[4]{}, reserved[4]{};
    for (u32 attempt = 0; attempt < 4; ++attempt) {
        parser.add(0x79, 0, 7);
        parser.add(0xbf, 8, 0);
        parser.add(0xbf, 1, 0);
        parser.add(0x77, 1, 0, 0, 32);
        owned[attempt] = parser.add(0x45, 1, 0, 0, static_cast<i32>(kHandoffOwned));
        pending[attempt] = parser.add(0x45, 1, 0, 0, kHandoffPending);
        // Until userspace publishes the validated response boundary, pass
        // one-byte frames. Afterwards clamp bulk pass frames to that boundary.
        parser.add(0xb7, 9, 0, 0, 1);
        parser.add(0x61, 2, 7, 24);
        parser.add(0xbc, 3, 8);
        const u32 kNoPassBody = parser.add(0xbd, 2, 3);
        parser.add(0x1f, 2, 3);
        parser.add(0xb7, 9, 0, 0, kHandoffFrameBytes);
        const u32 kBulkPassFrame = parser.add(0x3d, 2, 9);
        parser.add(0xbf, 9, 2);
        parser.jump(kNoPassBody, parser.count);
        parser.jump(kBulkPassFrame, parser.count);
        parser.add(0xbf, 3, 9);
        parser.add(0x47, 3, 0, 0, kHandoffPending);
        parser.add(0x67, 3, 0, 0, 32);
        parser.add(0x4f, 3, 8);
        parser.add(0xdb, 7, 3, 0, 0xf1);
        reserved[attempt] = parser.add(0x1d, 0, 8);
    }
    const u32 kParserExhausted = parser.add(0x05, 0);
    for (u32 const kBranch : owned) parser.jump(kBranch, parser.count);
    parser.add(0x57, 1, 0, 0, kHandoffBudgetMask);
    parser.add(0xb7, 9, 0, 0, 1);
    const u32 kPassFrame = parser.add(0x15, 1, 0, 0, 0);
    parser.add(0xb7, 9, 0, 0, kHandoffFrameBytes);
    const u32 kFullFrame = parser.add(0x3d, 1, 9);
    parser.add(0xbf, 9, 1);
    const u32 kSelected = parser.add(0x05, 0);
    for (u32 const kBranch : pending) parser.jump(kBranch, parser.count);
    parser.add(0xbf, 9, 1);
    parser.add(0x57, 9, 0, 0, kHandoffBudgetMask);
    for (u32 const kBranch : reserved) parser.jump(kBranch, parser.count);
    parser.jump(kPassFrame, parser.count);
    parser.jump(kFullFrame, parser.count);
    parser.jump(kSelected, parser.count);
    parser.add(0x63, 7, 9, 8);
    parser.add(0xbf, 0, 9);
    parser.add(0x95, 0);
    parser.jump(kParserExhausted, parser.count);
    parser.add(0x62, 7, 0, 12, 1);
    parser.jump(kParserMissing, parser.count);
    parser.add(0xb7, 0, 0, 0, -1);
    parser.add(0x95, 0);
    out.parser_count = parser.count;

    Builder verdict{out.verdict};
    out.verdict_state_map = verdict.state_lookup();
    const u32 kVerdictMissing = verdict.add(0x15, 0, 0, 0, 0);
    verdict.add(0xbf, 7, 0);
    verdict.add(0x61, 9, 7, 8);  // parser's logical frame, never skb.len
    u32 committed[4]{}, oversize[4]{}, overflow[4]{};
    for (u32 attempt = 0; attempt < 4; ++attempt) {
        verdict.add(0x79, 0, 7);
        verdict.add(0xbf, 8, 0);
        verdict.add(0xbf, 1, 0);
        verdict.add(0x77, 1, 0, 0, 32);
        const u32 kInitialPass = verdict.add(0x45, 1, 0, 0, kHandoffPending);
        verdict.add(0x57, 1, 0, 0, kHandoffBudgetMask);
        const u32 kPass = verdict.add(0x15, 1, 0, 0, 0);
        oversize[attempt] = verdict.add(0x2d, 9, 1);
        verdict.add(0xbf, 2, 9);
        verdict.add(0x67, 2, 0, 0, 32);
        verdict.add(0xbf, 3, 8);
        verdict.add(0x1f, 3, 2);
        const u32 kToCas = verdict.add(0x05, 0);
        verdict.jump(kInitialPass, verdict.count);
        verdict.add(0xbc, 3, 8);
        verdict.add(0xb7, 1, 0, 0, 0);
        const u32 kIncrement = verdict.add(0x05, 0);
        verdict.jump(kPass, verdict.count);
        verdict.add(0xbf, 3, 8);
        verdict.jump(kIncrement, verdict.count);
        verdict.add(0x0f, 3, 9);
        verdict.add(0xbf, 2, 3);
        verdict.add(0x77, 2, 0, 0, 32);
        verdict.add(0x57, 2, 0, 0, kHandoffBudgetMask);
        overflow[attempt] = verdict.add(0x55, 2, 0, 0, 0);
        verdict.jump(kToCas, verdict.count);
        verdict.add(0xdb, 7, 3, 0, 0xf1);
        committed[attempt] = verdict.add(0x1d, 0, 8);
    }
    for (u32 const kBranch : oversize) verdict.jump(kBranch, verdict.count);
    for (u32 const kBranch : overflow) verdict.jump(kBranch, verdict.count);
    verdict.add(0x62, 7, 0, 12, 1);
    verdict.add(0xb7, 0, 0, 0, 0);
    const u32 kFailed = verdict.add(0x05, 0);
    for (u32 const kBranch : committed) verdict.jump(kBranch, verdict.count);
    const u32 kPassed = verdict.add(0x15, 1, 0, 0, 0);
    verdict.add(0xbf, 1, 6);
    out.verdict_target_map = verdict.map(2);
    verdict.add(0xbf, 3, 7);
    verdict.add(0x07, 3, 0, 0, 16);  // target cookie key inside state
    verdict.add(0xb7, 4, 0, 0, 0);
    verdict.add(0x85, 0, 0, 0, 72);  // sk_redirect_hash
    const u32 kRedirected = verdict.add(0x55, 0, 0, 0, 0);
    verdict.add(0x62, 7, 0, 12, 1);
    verdict.jump(kRedirected, verdict.count);
    verdict.add(0x95, 0);
    verdict.jump(kPassed, verdict.count);
    verdict.add(0xb7, 0, 0, 0, 1);
    verdict.add(0x95, 0);
    verdict.jump(kFailed, verdict.count);
    verdict.jump(kVerdictMissing, verdict.count);
    verdict.add(0xb7, 0, 0, 0, 0);
    verdict.add(0x95, 0);
    out.verdict_count = verdict.count;

    Builder commit{out.commit};
    commit.add(0x62, 10, 0, -8, 0);
    out.commit_command_map = commit.map(1);
    commit.stack_key();
    commit.add(0x85, 0, 0, 0, kMapLookupHelper);
    const u32 kNoCommand = commit.add(0x15, 0, 0, 0, 0);
    commit.add(0xbf, 6, 0);
    out.commit_state_map = commit.map(1);
    commit.add(0xbf, 2, 6);  // command.source_cookie
    commit.add(0x85, 0, 0, 0, kMapLookupHelper);
    const u32 kNoState = commit.add(0x15, 0, 0, 0, 0);
    commit.add(0xbf, 7, 0);
    commit.add(0x61, 1, 7, 12);
    const u32 kStateFailed = commit.add(0x55, 1, 0, 0, 0);
    commit.add(0x79, 0, 6, 8);
    commit.add(0xbf, 8, 0);
    const u32 kPublishLimit = commit.add(0x15, 0, 0, 0, -1);
    commit.add(0x79, 3, 6, 16);
    commit.add(0xdb, 7, 3, 0, 0xf1);
    const u32 kMismatch = commit.add(0x5d, 0, 8);
    commit.add(0xb7, 0, 0, 0, 1);
    commit.add(0x95, 0);
    commit.jump(kPublishLimit, commit.count);
    commit.add(0x61, 3, 6, 16);
    const u32 kEmptyLimit = commit.add(0x15, 3, 0, 0, 0);
    commit.add(0xc3, 7, 3, 24, 0xe1);  // atomic u32 exchange of the pass boundary
    commit.add(0xb7, 0, 0, 0, 1);
    commit.add(0x95, 0);
    commit.jump(kEmptyLimit, commit.count);
    commit.jump(kNoCommand, commit.count);
    commit.jump(kNoState, commit.count);
    commit.jump(kStateFailed, commit.count);
    commit.jump(kMismatch, commit.count);
    commit.add(0xb7, 0, 0, 0, 0);
    commit.add(0x95, 0);
    out.commit_count = commit.count;
}
}  // namespace rut::ebpf

namespace rut::ebpf {
// Separate L4 experiment: the entire upstream stream is admitted before any
// request is sent. No HTTP body boundary or userspace takeover is implied.
inline void emit_tunnel_bytecode(HandoffCode& out) {
    out = {};
    handoff_detail::Builder verdict{out.verdict};
    out.verdict_state_map = verdict.state_lookup();
    const u32 kMissing = verdict.add(0x15, 0, 0, 0, 0);
    verdict.add(0xbf, 7, 0);
    verdict.add(0x61, 1, 7, 12);
    const u32 kFailed = verdict.add(0x55, 1, 0, 0, 0);
    verdict.add(0x61, 8, 6);  // skb length, preserved across redirect helper
    verdict.add(0xbf, 1, 6);
    out.verdict_target_map = verdict.map(2);
    verdict.add(0xbf, 3, 7);
    verdict.add(0x07, 3, 0, 0, 16);
    verdict.add(0xb7, 4, 0, 0, 0);
    verdict.add(0x85, 0, 0, 0, 72);
    const u32 kDropped = verdict.add(0x15, 0, 0, 0, 0);
    verdict.add(0xdb, 7, 8, 0, 0);  // atomic u64 add of accepted redirect bytes
    verdict.add(0xb7, 0, 0, 0, 1);
    verdict.add(0x95, 0);
    verdict.jump(kDropped, verdict.count);
    verdict.add(0x62, 7, 0, 12, 1);
    verdict.jump(kMissing, verdict.count);
    verdict.jump(kFailed, verdict.count);
    verdict.add(0xb7, 0, 0, 0, 0);
    verdict.add(0x95, 0);
    out.verdict_count = verdict.count;
}
// Packet verdict avoids strparser buffering and framing work. Whole packets
// inside the remaining body redirect; a packet crossing the boundary is passed
// back for userspace to forward only its body prefix, after a TX ordering barrier.
inline void emit_packet_handoff_bytecode(HandoffCode& out) {
    emit_handoff_bytecode(out);
    for (auto& op : out.parser) op = {};
    for (auto& op : out.verdict) op = {};
    out.parser_count = 0;
    out.parser_state_map = 0;
    using handoff_detail::Builder;
    Builder verdict{out.verdict};
    out.verdict_state_map = verdict.state_lookup();
    const u32 kMissing = verdict.add(0x15, 0, 0, 0, 0);
    verdict.add(0xbf, 7, 0);
    verdict.add(0x61, 1, 7, 12);
    const u32 kAlreadyFailed = verdict.add(0x55, 1, 0, 0, 0);
    verdict.add(0x61, 9, 6, 0);  // full packet payload, no strparser offset
    u32 committed[4]{}, overflow[4]{};
    for (u32 attempt = 0; attempt < 4; ++attempt) {
        verdict.add(0x79, 0, 7);
        verdict.add(0xbf, 8, 0);
        verdict.add(0xbf, 1, 0);
        verdict.add(0x77, 1, 0, 0, 32);
        verdict.add(0x57, 1, 0, 0, kHandoffBudgetMask);
        const u32 kPass = verdict.add(0x15, 1, 0, 0, 0);
        const u32 kCrossing = verdict.add(0x2d, 9, 1);
        verdict.add(0xbf, 2, 9);
        verdict.add(0x67, 2, 0, 0, 32);
        verdict.add(0xbf, 3, 8);
        verdict.add(0x1f, 3, 2);
        const u32 kToCas = verdict.add(0x05, 0);
        verdict.jump(kCrossing, verdict.count);
        verdict.add(0x63, 7, 1, 28);  // body prefix that userspace must still send
        verdict.add(0xbc, 3, 8);
        verdict.add(0xb4, 2, 0, 0, static_cast<i32>(kHandoffOwned));
        verdict.add(0x57, 2, 0, 0, static_cast<i32>(~kHandoffBudgetMask));
        verdict.add(0x67, 2, 0, 0, 32);
        verdict.add(0x4f, 3, 2);
        verdict.add(0xb7, 1, 0, 0, 0);
        const u32 kIncrement = verdict.add(0x05, 0);
        verdict.jump(kPass, verdict.count);
        verdict.add(0xbf, 3, 8);
        verdict.jump(kIncrement, verdict.count);
        verdict.add(0x0f, 3, 9);
        verdict.add(0xbf, 2, 3);
        verdict.add(0x77, 2, 0, 0, 32);
        verdict.add(0x57, 2, 0, 0, kHandoffBudgetMask);
        overflow[attempt] = verdict.add(0x55, 2, 0, 0, 0);
        verdict.jump(kToCas, verdict.count);
        verdict.add(0xdb, 7, 3, 0, 0xf1);
        committed[attempt] = verdict.add(0x1d, 0, 8);
    }
    for (u32 const kBranch : overflow) verdict.jump(kBranch, verdict.count);
    verdict.add(0x62, 7, 0, 12, 1);
    verdict.add(0xb7, 0, 0, 0, 0);
    const u32 kFailed = verdict.add(0x05, 0);
    for (u32 const kBranch : committed) verdict.jump(kBranch, verdict.count);
    const u32 kPassed = verdict.add(0x15, 1, 0, 0, 0);
    verdict.add(0xbf, 1, 6);
    out.verdict_target_map = verdict.map(2);
    verdict.add(0xbf, 3, 7);
    verdict.add(0x07, 3, 0, 0, 16);
    verdict.add(0xb7, 4, 0, 0, 0);
    verdict.add(0x85, 0, 0, 0, 72);
    const u32 kRedirected = verdict.add(0x55, 0, 0, 0, 0);
    verdict.add(0x62, 7, 0, 12, 1);
    verdict.jump(kRedirected, verdict.count);
    const u32 kRedirectFinished = verdict.add(0x05, 0);
    verdict.jump(kPassed, verdict.count);
    verdict.add(0xb7, 0, 0, 0, 1);
    verdict.jump(kFailed, verdict.count);
    const u32 kNotifyFailure = verdict.count;
    verdict.add(0x61, 1, 7, 12);
    const u32 kFailureNotify = verdict.add(0x55, 1, 0, 0, 0);
    verdict.jump(kRedirectFinished, kNotifyFailure);
    verdict.add(0xbf, 1, 8);
    verdict.add(0x77, 1, 0, 0, 32);
    verdict.add(0x57, 1, 0, 0, kHandoffBudgetMask);
    const u32 kNoTransition = verdict.add(0x15, 1, 0, 0, 0);
    verdict.add(0x79, 1, 7);
    verdict.add(0x77, 1, 0, 0, 32);
    verdict.add(0x57, 1, 0, 0, kHandoffBudgetMask);
    const u32 kStillActive = verdict.add(0x55, 1, 0, 0, 0);
    verdict.jump(kFailureNotify, verdict.count);
    verdict.add(0xbf, 9, 0);  // preserve SK_PASS/SK_DROP across notification helper
    verdict.add(0x79, 1, 10, -8);
    verdict.add(0x7b, 10, 1, -32);
    verdict.add(0x79, 1, 7, 32);
    verdict.add(0x7b, 10, 1, -24);
    out.verdict_ring_map = verdict.map(1);
    verdict.add(0xbf, 2, 10);
    verdict.add(0x07, 2, 0, 0, -32);
    verdict.add(0xb7, 3, 0, 0, sizeof(HandoffNotification));
    verdict.add(0xb7, 4, 0, 0, 0);
    verdict.add(0x85, 0, 0, 0, 130);  // ringbuf_output
    const u32 kNotified = verdict.add(0x15, 0, 0, 0, 0);
    verdict.add(0x62, 7, 0, 12, 1);
    verdict.jump(kNotified, verdict.count);
    verdict.add(0xbf, 0, 9);
    verdict.jump(kNoTransition, verdict.count);
    verdict.jump(kStillActive, verdict.count);
    verdict.add(0x95, 0);
    verdict.jump(kMissing, verdict.count);
    verdict.jump(kAlreadyFailed, verdict.count);
    verdict.add(0xb7, 0, 0, 0, 0);
    verdict.add(0x95, 0);
    out.verdict_count = verdict.count;
}
}  // namespace rut::ebpf
