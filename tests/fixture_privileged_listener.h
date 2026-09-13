#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rut::test::fixture_privileged_listener {

inline constexpr std::size_t kMaxProcBytes = 16u * 1024u;
inline constexpr std::size_t kMaxProcRows = 128u;
inline constexpr std::size_t kMaxOwnedSocketInodes = 8u;
inline constexpr std::size_t kMaxCollisionLogBytes = 4096u;

enum class DiagnosticPhase : std::uint8_t {
    None,
    Plan,
    Source,
    ProcHeader,
    ProcRow,
    Ownership,
    Evidence,
    CollisionLog,
};

struct Diagnostic {
    DiagnosticPhase phase = DiagnosticPhase::None;
    std::size_t row_count = 0u;
    std::size_t match_count = 0u;
    std::size_t owned_count = 0u;
    int error_number = 0;
};

struct ListenerPlan {
    // Canonical host-order IPv4 values (for example 10.1.2.3 is 0x0a010203).
    std::uint32_t positive_ipv4 = 0u;
    std::uint32_t guard_ipv4 = 0u;
    // Kept wide until validation rejects values outside 1..65535.
    std::uint64_t port = 0u;
};

struct ListenerPlanText {
    std::string positive_ipv4;
    std::string guard_ipv4;
    std::string positive_endpoint;
    std::string guard_endpoint;
    std::string wildcard_endpoint;
};

bool validate_listener_plan(const ListenerPlan& plan,
                            ListenerPlanText& text,
                            Diagnostic& diagnostic);

enum class ListenerSourceKind : std::uint8_t { Exact, Wildcard };

bool build_listener_source(const ListenerPlan& plan,
                           ListenerSourceKind kind,
                           std::string& source,
                           Diagnostic& diagnostic);

struct ProcTcpRecord {
    std::uint32_t local_ipv4 = 0u;
    std::uint16_t local_port = 0u;
    std::uint32_t remote_ipv4 = 0u;
    std::uint16_t remote_port = 0u;
    std::uint8_t state = 0u;
    std::uint64_t inode = 0u;
};

struct ProcTcpTable {
    std::array<ProcTcpRecord, kMaxProcRows> rows{};
    std::size_t count = 0u;
};

bool parse_proc_net_tcp(const std::string& contents, ProcTcpTable& table, Diagnostic& diagnostic);

struct GuardReservationEvidence {
    std::uint64_t target_owned_inode = 0u;
};

// Linux does not publish a merely bound, non-listening TCP socket in
// /proc/net/tcp. Require complete selected-port absence while preserving the
// independently observed target-owned socket inode as the guard witness.
bool classify_guard_reservation(const ProcTcpTable& table,
                                const ListenerPlan& plan,
                                std::uint64_t target_owned_socket_inode,
                                GuardReservationEvidence& evidence,
                                Diagnostic& diagnostic);

enum class ListenerEvidenceKind : std::uint8_t {
    ExactPositive,
    Wildcard,
    // No /proc/net/tcp record of any state may retain the selected port.
    PortAbsent,
};

struct ListenerEvidence {
    ListenerEvidenceKind kind = ListenerEvidenceKind::PortAbsent;
    // Wildcard LISTEN covers guard_ipv4:port; exact-positive and complete-port-
    // absence evidence do not. A separate authenticated guard FD proves that
    // its non-listening reservation is held during the exact phase.
    bool guard_covered_by_listener = false;
    std::uint64_t child_owned_inode = 0u;
};

bool classify_listener_evidence(const ProcTcpTable& table,
                                const ListenerPlan& plan,
                                const std::vector<std::uint64_t>& child_owned_socket_inodes,
                                ListenerEvidenceKind expected,
                                ListenerEvidence& evidence,
                                Diagnostic& diagnostic);

enum class CollisionBackend : std::uint8_t { Epoll, IoUring };

struct CollisionLogEvidence {
    CollisionBackend backend = CollisionBackend::Epoll;
    std::uint8_t optimization_level = 0u;
    int error_number = 0;
};

bool classify_collision_log(const std::string& log,
                            const std::string& expected_source_path,
                            std::uint8_t expected_optimization_level,
                            CollisionLogEvidence& evidence,
                            Diagnostic& diagnostic);

}  // namespace rut::test::fixture_privileged_listener
