#include "rut/runtime/direct_body_recv_phase.h"

namespace rut {
namespace {

consteval bool direct_body_recv_phase_contract() {
    using Phase = ResponseReadDeadlinePostCommitPhase;
    using Mode = ForwardResponseBufferingMode;
    struct PhaseRule {
        Phase phase;
        bool buffering;
        bool streaming;
    };
    constexpr PhaseRule kRules[] = {
        {Phase::None, false, false},
        {Phase::Buffering, true, false},
        {Phase::HeaderSend, false, true},
        {Phase::BodySend, false, true},
        {Phase::WaitingBody, false, true},
        {Phase::OriginComplete, false, false},
        {Phase::CombinedSend, false, false},
    };
    constexpr Mode kModes[] = {Mode::None, Mode::CompleteContentLength, Mode::Bounded};
    for (const auto& rule : kRules) {
        for (const Mode kMode : kModes) {
            const bool kStream = kMode == Mode::Bounded && rule.streaming;
            if (bounded_body_recv_phase(kMode, rule.phase) != kStream) return false;
            for (unsigned flags = 0; flags < 4; ++flags) {
                const bool kCommit = rule.buffering || (kStream && flags == 0);
                if (direct_body_recv_commit_phase(kMode, rule.phase, flags & 1u, flags & 2u) !=
                    kCommit)
                    return false;
            }
        }
    }
    return true;
}

static_assert(direct_body_recv_phase_contract(), "Direct body receive violates phase contract");

}  // namespace
}  // namespace rut
