#pragma once

#include "fixture_collision_release_evidence_protocol.h"
#include <chrono>
#include <cstddef>
#include <cstdint>

#include <poll.h>
#include <sys/types.h>

namespace rut::test::fixture_collision_release_evidence_transport {

namespace worker = fixture_worker_protocol;
using Clock = std::chrono::steady_clock;

inline constexpr worker::u16 kEvidenceFrameType = 59u;
inline constexpr std::size_t kHeaderBytes = worker::kHeaderBytes;
inline constexpr std::size_t kMaxPayload = worker::kMaxPayload;
inline constexpr std::size_t kEnvelopeBytes =
    fixture_collision_release_evidence_protocol::kEnvelopeBytes;
static_assert(kHeaderBytes == 44u);
static_assert(kEvidenceFrameType ==
              fixture_collision_release_evidence_protocol::kEvidenceFrameType);
static_assert(kEnvelopeBytes <= kMaxPayload);

enum class DiagnosticCode : std::uint8_t {
    None = 0,
    Argument,
    Deadline,
    CleanEofBeforeHeader,
    TruncatedHeader,
    TruncatedPayload,
    PollError,
    SyscallError,
    BadMagic,
    BadVersion,
    BadType,
    BadToken,
    PayloadTooSmall,
    PayloadTooLarge,
};

enum class Stage : std::uint8_t {
    None = 0,
    ReadHeader,
    ReadPayload,
    WriteHeader,
    WritePayload,
};

struct Diagnostic {
    DiagnosticCode code = DiagnosticCode::None;
    Stage stage = Stage::None;
    int error_number = 0;
    std::size_t bytes_transferred = 0;

    bool operator==(const Diagnostic&) const = default;
};

struct HooksForTesting {
    using Poll = int (*)(pollfd*, nfds_t, int, void*);
    using Recv = ssize_t (*)(int, void*, std::size_t, int, void*);
    using Send = ssize_t (*)(int, const void*, std::size_t, int, void*);

    Poll poll = nullptr;
    Recv recv = nullptr;
    Send send = nullptr;
    void* context = nullptr;
};

bool receive_frame(int fd,
                   const worker::Token& expected_token,
                   std::size_t maximum_payload,
                   Clock::time_point deadline,
                   worker::Frame& output,
                   Diagnostic& diagnostic,
                   const HooksForTesting& hooks = {});

bool send_frame(int fd,
                const worker::Token& expected_token,
                std::size_t maximum_payload,
                Clock::time_point deadline,
                const worker::Frame& frame,
                Diagnostic& diagnostic,
                const HooksForTesting& hooks = {});

}  // namespace rut::test::fixture_collision_release_evidence_transport
