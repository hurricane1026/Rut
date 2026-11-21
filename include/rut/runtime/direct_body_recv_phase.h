#pragma once

#include "rut/common/failure_policy.h"
#include "rut/common/types.h"

namespace rut {

enum class ResponseReadDeadlinePostCommitPhase : u8 {
    None,
    // The strict response header is pinned, but no downstream byte has been
    // published.  Positive Content-Length bytes remain behind the header in
    // upstream_recv_buf until a terminal buffering disposition is selected.
    Buffering,
    HeaderSend,
    BodySend,
    WaitingBody,
    OriginComplete,
    CombinedSend,
};

// Every new phase must explicitly opt in or out of bounded streaming.
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch-enum"
#pragma GCC diagnostic error "-Wswitch"
constexpr bool bounded_body_recv_phase(ForwardResponseBufferingMode mode,
                                       ResponseReadDeadlinePostCommitPhase phase) {
    using Phase = ResponseReadDeadlinePostCommitPhase;
    switch (phase) {
        case Phase::HeaderSend:
        case Phase::BodySend:
        case Phase::WaitingBody:
            return mode == ForwardResponseBufferingMode::Bounded;
        case Phase::None:
        case Phase::Buffering:
        case Phase::OriginComplete:
        case Phase::CombinedSend:
            return false;
    }
    return false;
}
#pragma GCC diagnostic pop

// Buffering has its own pre-publication settlement path. Once streaming,
// a frozen terminal disposition makes subsequent physical writes custody-only.
constexpr bool direct_body_recv_commit_phase(ForwardResponseBufferingMode mode,
                                             ResponseReadDeadlinePostCommitPhase phase,
                                             bool terminal_pending,
                                             bool close_after_drain) {
    return phase == ResponseReadDeadlinePostCommitPhase::Buffering ||
           (bounded_body_recv_phase(mode, phase) && !terminal_pending && !close_after_drain);
}

}  // namespace rut
